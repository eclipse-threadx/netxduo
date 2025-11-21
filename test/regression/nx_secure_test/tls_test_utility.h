#ifndef __TLS_TEST_UTILITY_H
#define __TLS_TEST_UTILITY_H

#ifndef NX_CRYPTO_STANDALONE_ENABLE
#include "nx_secure_tls_api.h"


void nx_secure_tls_test_init_utility(NX_SECURE_TLS_SESSION *tls_session);

UINT  _txe_mutex_get(TX_MUTEX *mutex_ptr, ULONG wait_option);
UINT  _txe_mutex_put(TX_MUTEX *mutex_ptr);
#else
#include "nx_crypto.h"
#endif

extern void    test_control_return(UINT status);

// Utility function to print buffer
static void print_buffer(const UCHAR* buf, ULONG size)
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


#define TEST(prefix, name)  void prefix ## _ ##name()
#define EXPECT_EQ(expected, actual) \
    if((expected) != (actual))          \
    {                               \
        printf("\nERROR! File: %s Line: %d\n", __FILE__, __LINE__); \
        printf("Expected: 0x%x, (%d) Got: 0x%x (%d)\n", (UINT)(expected), (INT)(expected), (UINT)(actual), (INT)(actual)); \
        test_control_return(1); \
    }

#define EXPECT_TRUE(statement) \
    if(!(statement))          \
    {                               \
        printf("\nERROR! File: %s Line: %d\n", __FILE__, __LINE__); \
        printf("Expected statement to be true!\n"); \
        test_control_return(1); \
    }



#endif
