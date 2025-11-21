#ifndef __TEST_UTILITY_H
#define __TEST_UTILITY_H

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


UINT  _txe_mutex_get(TX_MUTEX *mutex_ptr, ULONG wait_option);
UINT  _txe_mutex_put(TX_MUTEX *mutex_ptr);


#define TEST(prefix, name)  void prefix ## _ ##name()
#define EXPECT_EQ(expected, actual) \
    if(expected != actual)          \
    {                               \
        printf("\nERROR! File: %s Line: %d\n", __FILE__, __LINE__); \
        printf("Expected: 0x%x, (%d) Got: 0x%x (%d)\n", expected, expected, actual, actual); \
        test_control_return(1); \
    }

#define EXPECT_TRUE(statement) \
    if(!statement)          \
    {                               \
        printf("\nERROR! File: %s Line: %d\n", __FILE__, __LINE__); \
        printf("Expected statement to be true!\n"); \
        test_control_return(1); \
    }



#endif
