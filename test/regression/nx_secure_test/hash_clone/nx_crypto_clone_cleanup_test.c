

#include "nx_crypto_clone_cleanup_test.h"


static NX_CRYPTO_CLONE_CLEANUP_TEST crypto_instances[NX_CRYPTO_HASH_INSTANCE_COUNT];
static UINT hash_error_counter;


NX_CRYPTO_KEEP UINT  _nx_crypto_clone_cleanup_test_initialize(NX_CRYPTO_CLONE_CLEANUP_TEST *context, UINT algorithm )
{
UINT status;
  
    /* Determine if the context is non-null.  */
    if (context == NX_CRYPTO_NULL)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    switch (context -> nx_crypto_hash_algorithm)
    {
    case NX_CRYPTO_HASH_SHA224:
    case NX_CRYPTO_HASH_SHA256:
        status = _nx_crypto_sha256_initialize((NX_CRYPTO_SHA256 *)context -> nx_crypto_hash_metadata, algorithm);
        break;
    }
    

    /* Return success.  */
    return(status);
}


NX_CRYPTO_KEEP UINT _nx_crypto_clone_cleanup_test_update(NX_CRYPTO_CLONE_CLEANUP_TEST *context, UCHAR *input_ptr, UINT input_length)
{
UINT status;

    /* Determine if the context is non-null.  */
    if (context == NX_CRYPTO_NULL)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    /* Determine if there is a length.  */
    if (input_length == 0)
    {
        return(NX_CRYPTO_SUCCESS);
    }

    switch (context -> nx_crypto_hash_algorithm)
    {
    case NX_CRYPTO_HASH_SHA224:
    case NX_CRYPTO_HASH_SHA256:
        status = _nx_crypto_sha256_update((NX_CRYPTO_SHA256 *)context -> nx_crypto_hash_metadata, input_ptr, input_length);
        break;
    }


    /* Return success.  */
    return(status);
}


NX_CRYPTO_KEEP UINT _nx_crypto_clone_cleanup_test_digest_calculate(NX_CRYPTO_CLONE_CLEANUP_TEST *context, UCHAR *digest, UINT algorithm)
{
UINT status;

    switch (context -> nx_crypto_hash_algorithm)
    {
    case NX_CRYPTO_HASH_SHA224:
    case NX_CRYPTO_HASH_SHA256:
        status = _nx_crypto_sha256_digest_calculate((NX_CRYPTO_SHA256 *)context -> nx_crypto_hash_metadata, digest, algorithm);
        break;
    }
    /* Return successful completion.  */
    return(status);
}



NX_CRYPTO_KEEP UINT  _nx_crypto_method_clone_cleanup_test_init(struct  NX_CRYPTO_METHOD_STRUCT *method,
                                                   UCHAR *key, NX_CRYPTO_KEY_SIZE key_size_in_bits,
                                                   VOID  **handle,
                                                   VOID  *crypto_metadata,
                                                   ULONG crypto_metadata_size)
{
NX_CRYPTO_HASH_CLONE *ctx;
UINT i;
UINT status = NX_CRYPTO_SUCCESS;

    NX_CRYPTO_PARAMETER_NOT_USED(key);
    NX_CRYPTO_PARAMETER_NOT_USED(key_size_in_bits);
    NX_CRYPTO_PARAMETER_NOT_USED(handle);

    if ((method == NX_CRYPTO_NULL) || (crypto_metadata == NX_CRYPTO_NULL))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_HASH_CLONE))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }
    
    ctx = (NX_CRYPTO_HASH_CLONE *)crypto_metadata;

    for (i = 0; i < NX_CRYPTO_HASH_INSTANCE_COUNT; i++)
    {
        if (crypto_instances[i].nx_crypto_hash_operation == 0)
        {
            ctx -> nx_crypto_hash_operation = i + 1;
            crypto_instances[i].nx_crypto_hash_operation = i + 1;
            crypto_instances[i].nx_crypto_hash_initialized = 1;
            crypto_instances[i].nx_crypto_hash_cloned = 0;
            crypto_instances[i].nx_crypto_hash_calculated = 0;
            crypto_instances[i].nx_crypto_hash_algorithm = method -> nx_crypto_algorithm;

            NX_CRYPTO_MEMSET(crypto_instances[i].nx_crypto_hash_metadata, 0, NX_CRYPTO_HASH_METADATA_SIZE);

            switch (crypto_instances[i].nx_crypto_hash_algorithm)
            {
            case NX_CRYPTO_HASH_SHA224:
            case NX_CRYPTO_HASH_SHA256:
                status = _nx_crypto_method_sha256_init(method, key, key_size_in_bits, handle,
                                                       crypto_instances[i].nx_crypto_hash_metadata, NX_CRYPTO_HASH_METADATA_SIZE);
                break;
            }

            return(status);
        }
    }
    
    hash_error_counter++;
    return(NX_CRYPTO_NO_INSTANCE);
}


NX_CRYPTO_KEEP UINT  _nx_crypto_method_clone_cleanup_test_cleanup(VOID *crypto_metadata)
{
NX_CRYPTO_HASH_CLONE *ctx;
NX_CRYPTO_CLONE_CLEANUP_TEST *inst;
UINT status = NX_CRYPTO_SUCCESS;

    if (!crypto_metadata)
    {
        hash_error_counter++;
        return (NX_CRYPTO_SUCCESS);
    }
 
    ctx = (NX_CRYPTO_HASH_CLONE *)crypto_metadata;

    if (ctx -> nx_crypto_hash_operation == 0 || ctx -> nx_crypto_hash_operation > NX_CRYPTO_HASH_INSTANCE_COUNT)
    {
        hash_error_counter++;
        return (NX_CRYPTO_SUCCESS);
    }

    inst = &crypto_instances[ctx -> nx_crypto_hash_operation - 1];

    if (inst -> nx_crypto_hash_operation != ctx -> nx_crypto_hash_operation)
    {
        hash_error_counter++;
        return(NX_CRYPTO_PTR_ERROR);
    }

    if (inst -> nx_crypto_hash_initialized == 0)
    {
        hash_error_counter++;
        return (NX_CRYPTO_PTR_ERROR);

    }

    switch (inst -> nx_crypto_hash_algorithm)
    {
    case NX_CRYPTO_HASH_SHA224:
    case NX_CRYPTO_HASH_SHA256:
        status = _nx_crypto_method_sha256_cleanup(inst -> nx_crypto_hash_metadata);
        break;
    }

    inst -> nx_crypto_hash_initialized--;

    if (inst -> nx_crypto_hash_initialized == 0)
    {
        inst -> nx_crypto_hash_operation = 0;
        ctx -> nx_crypto_hash_operation = 0;
    }


    return(status);
}


NX_CRYPTO_KEEP UINT  _nx_crypto_method_clone_cleanup_test_operation(UINT op,      /* Encrypt, Decrypt, Authenticate */
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
NX_CRYPTO_HASH_CLONE *ctx;
NX_CRYPTO_CLONE_CLEANUP_TEST *inst;
UINT i;

    NX_CRYPTO_PARAMETER_NOT_USED(handle);
    NX_CRYPTO_PARAMETER_NOT_USED(key);
    NX_CRYPTO_PARAMETER_NOT_USED(key_size_in_bits);
    NX_CRYPTO_PARAMETER_NOT_USED(iv_ptr);
    NX_CRYPTO_PARAMETER_NOT_USED(packet_ptr);
    NX_CRYPTO_PARAMETER_NOT_USED(nx_crypto_hw_process_callback);


    if (method == NX_CRYPTO_NULL)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if((crypto_metadata == NX_CRYPTO_NULL))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    if(crypto_metadata_size < sizeof(NX_CRYPTO_HASH_CLONE))
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    ctx = (NX_CRYPTO_HASH_CLONE *)crypto_metadata;

    if (ctx -> nx_crypto_hash_operation == 0 || ctx -> nx_crypto_hash_operation > NX_CRYPTO_HASH_INSTANCE_COUNT)
    {
        hash_error_counter++;
        return (NX_CRYPTO_SUCCESS);
    }

    inst = &crypto_instances[ctx -> nx_crypto_hash_operation - 1];

    if (inst -> nx_crypto_hash_operation != ctx -> nx_crypto_hash_operation)
    {
        hash_error_counter++;
        return(NX_CRYPTO_PTR_ERROR);
    }

    if (inst -> nx_crypto_hash_initialized == 0)
    {
        hash_error_counter++;
        return (NX_CRYPTO_PTR_ERROR);
    }

    switch (op)
    {
    case NX_CRYPTO_HASH_INITIALIZE:
        _nx_crypto_clone_cleanup_test_initialize(inst, method -> nx_crypto_algorithm);
        break;

    case NX_CRYPTO_HASH_UPDATE:
        _nx_crypto_clone_cleanup_test_update(inst, input, input_length_in_byte);
        break;

    case NX_CRYPTO_HASH_CALCULATE:
        if ((method -> nx_crypto_algorithm == NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256) ||
            (method -> nx_crypto_algorithm == NX_CRYPTO_HASH_SHA256))
        {
            if(output_length_in_byte < 32)
                return(NX_CRYPTO_INVALID_BUFFER_SIZE);
        }
        else if(output_length_in_byte < 28)
            return(NX_CRYPTO_INVALID_BUFFER_SIZE);
        _nx_crypto_clone_cleanup_test_digest_calculate(inst, output,
                                           method -> nx_crypto_algorithm);
        break;

    default:
        if ((method -> nx_crypto_algorithm == NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256) ||
            (method -> nx_crypto_algorithm == NX_CRYPTO_HASH_SHA256))
        {
            if(output_length_in_byte < 32)
                return(NX_CRYPTO_INVALID_BUFFER_SIZE);
        }
        else if(output_length_in_byte < 28)
            return(NX_CRYPTO_INVALID_BUFFER_SIZE);

        for (i = 0; i < NX_CRYPTO_HASH_INSTANCE_COUNT; i++)
        {
            if (crypto_instances[i].nx_crypto_hash_operation == 0)
            {
                crypto_instances[i].nx_crypto_hash_initialized = 1;
                crypto_instances[i].nx_crypto_hash_cloned = 0;
                crypto_instances[i].nx_crypto_hash_calculated = 0;
                crypto_instances[i].nx_crypto_hash_algorithm = method -> nx_crypto_algorithm;

                NX_CRYPTO_MEMSET(crypto_instances[i].nx_crypto_hash_metadata, 0, NX_CRYPTO_HASH_METADATA_SIZE);
                _nx_crypto_clone_cleanup_test_initialize(&crypto_instances[i], method -> nx_crypto_algorithm);
                _nx_crypto_clone_cleanup_test_update(&crypto_instances[i], input, input_length_in_byte);
                _nx_crypto_clone_cleanup_test_digest_calculate(&crypto_instances[i], output, method -> nx_crypto_algorithm);
                return(NX_CRYPTO_SUCCESS);
            }
        }

        hash_error_counter++;
        return(NX_CRYPTO_NO_INSTANCE);


        break;
    }

    return NX_CRYPTO_SUCCESS;
}

UINT nx_crypto_clone_cleanup_test_clone(VOID *dest_metadata, VOID *source_metadata, ULONG length)
{
NX_CRYPTO_CLONE_CLEANUP_TEST *src_inst;
NX_CRYPTO_HASH_CLONE *ctx;
UINT i;

    if (length != sizeof(NX_CRYPTO_HASH_CLONE))
    {
        hash_error_counter++;
        return(NX_CRYPTO_PTR_ERROR);
    }
    
    ctx = (NX_CRYPTO_HASH_CLONE *)source_metadata;

    if (ctx -> nx_crypto_hash_operation == 0 || ctx -> nx_crypto_hash_operation > NX_CRYPTO_HASH_INSTANCE_COUNT)
    {
        hash_error_counter++;
        return (NX_CRYPTO_PTR_ERROR);
    }

    src_inst = &crypto_instances[ctx -> nx_crypto_hash_operation - 1];

    if (src_inst -> nx_crypto_hash_operation != ctx -> nx_crypto_hash_operation)
    {
        hash_error_counter++;
        return(NX_CRYPTO_PTR_ERROR);
    }

    if (src_inst -> nx_crypto_hash_initialized == 0)
    {
        hash_error_counter++;
        return (NX_CRYPTO_PTR_ERROR);
    }

    ctx = (NX_CRYPTO_HASH_CLONE *)dest_metadata;

    for (i = 0; i < NX_CRYPTO_HASH_INSTANCE_COUNT; i++)
    {
        if (crypto_instances[i].nx_crypto_hash_operation == 0)
        {
            ctx -> nx_crypto_hash_operation = i + 1;
            crypto_instances[i].nx_crypto_hash_operation = i + 1;
            crypto_instances[i].nx_crypto_hash_initialized = 1;
            crypto_instances[i].nx_crypto_hash_cloned = 1;
            crypto_instances[i].nx_crypto_hash_calculated = 0;
            crypto_instances[i].nx_crypto_hash_algorithm = src_inst -> nx_crypto_hash_algorithm;

            NX_CRYPTO_MEMCPY(crypto_instances[i].nx_crypto_hash_metadata, src_inst -> nx_crypto_hash_metadata, NX_CRYPTO_HASH_METADATA_SIZE);
            return(NX_CRYPTO_SUCCESS);
        }
    }

    hash_error_counter++;
    return(NX_CRYPTO_NO_INSTANCE);
}

UINT nx_crypto_clone_cleanup(VOID *metadata, ULONG length)
{
UINT status;

    if (length != sizeof(NX_CRYPTO_HASH_CLONE))
    {
        return(NX_CRYPTO_SUCCESS);
    }

    status = _nx_crypto_method_clone_cleanup_test_cleanup(metadata);

    return(status);
}

UINT check_cleanup_error()
{
    UINT i;

    if (hash_error_counter)
    {
        return(hash_error_counter);
    }

    for (i = 0; i < NX_CRYPTO_HASH_INSTANCE_COUNT; i++)
    {
        if (crypto_instances[i].nx_crypto_hash_operation)
        {
            return(NX_CRYPTO_NO_INSTANCE);
        }
    }
    return(NX_CRYPTO_SUCCESS);
}