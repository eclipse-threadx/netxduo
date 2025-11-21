

#include "nx_crypto_hash_clone_test.h"




NX_CRYPTO_KEEP UINT  _nx_crypto_method_hash_clone_test_init(struct  NX_CRYPTO_METHOD_STRUCT *method,
                                                   UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                                   VOID  **handle,
                                                   VOID  *crypto_metadata,
                                                   ULONG crypto_metadata_size)
{
UINT status;

    if ((method == NX_CRYPTO_NULL) || (crypto_metadata == NX_CRYPTO_NULL))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    /* Verify the metadata addrsss is 4-byte aligned. */
    if((((ULONG)crypto_metadata) & 0x3) != 0)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_HASH_CLONE_TEST))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }
    
    
    NX_CRYPTO_MEMSET(crypto_metadata, 0, sizeof(NX_CRYPTO_HASH_CLONE_TEST));

    status = _nx_crypto_method_clone_cleanup_test_init(method, key, key_size_in_bits,
                                                       handle, crypto_metadata, crypto_metadata_size);

    return(status);
}


NX_CRYPTO_KEEP UINT  _nx_crypto_method_hash_clone_test_cleanup(VOID *crypto_metadata)
{
UINT status;

    if (!crypto_metadata)
        return (NX_CRYPTO_SUCCESS);

    
    status = _nx_crypto_method_clone_cleanup_test_cleanup(crypto_metadata);

    return(status);
}


NX_CRYPTO_KEEP UINT  _nx_crypto_method_hash_clone_test_operation(UINT op,      /* Encrypt, Decrypt, Authenticate */
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
UINT status;

    if (method == NX_CRYPTO_NULL)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    /* Verify the metadata addrsss is 4-byte aligned. */
    if((crypto_metadata == NX_CRYPTO_NULL) || ((((ULONG)crypto_metadata) & 0x3) != 0))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_HASH_CLONE_TEST))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }


    status = _nx_crypto_method_clone_cleanup_test_operation(op, handle, method, key, key_size_in_bits,
                                                            input, input_length_in_byte, iv_ptr,
                                                            output, output_length_in_byte,
                                                            crypto_metadata, crypto_metadata_size,
                                                            packet_ptr, nx_crypto_hw_process_callback);

    return(status);
}

UINT nx_crypto_hash_clone_test_clone(VOID *dest_metadata, VOID *source_metadata, ULONG length)
{

    if (length != sizeof(NX_CRYPTO_HASH_CLONE_TEST))
    {
        NX_CRYPTO_MEMCPY(dest_metadata, source_metadata, length);
        return(NX_CRYPTO_SUCCESS);
    }
    
    return(nx_crypto_clone_cleanup_test_clone(dest_metadata, source_metadata, length));
}