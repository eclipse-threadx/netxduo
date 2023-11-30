/* This NetX test concentrates on the utility functions.  */

#include   "nx_md5.h"
#include   "tx_api.h"
#include   "nx_api.h"

#define DEMO_STACK_SIZE         2048

/* Define the ThreadX and NetX object control blocks...  */

static TX_THREAD               ntest_0;

/* Define thread prototypes.  */

static void  ntest_0_entry(ULONG thread_input);
extern void  test_control_return(UINT status);

/* Define what the initial system looks like.  */

#ifdef CTEST
VOID test_application_define(void *first_unused_memory)
#else
void    netx_utility_test_application_define(void *first_unused_memory)
#endif
{

CHAR    *pointer;


    /* Setup the working pointer.  */
    pointer =  (CHAR *) first_unused_memory;

    /* Create the main thread.  */
    tx_thread_create(&ntest_0, "thread 0", ntest_0_entry, 0,  
            pointer, DEMO_STACK_SIZE, 
            4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
    pointer =  pointer + DEMO_STACK_SIZE;

    /* Initialize the NetX system.  */
    nx_system_initialize();
}


/* Define the test threads.  */

static void    ntest_0_entry(ULONG thread_input)
{

UINT        status;
UINT        string_length;
UINT        number;
UCHAR       input_buffer[256] = {0};
UCHAR       out_buffer[256] = {0};
UINT        bytes_copied;
UINT        i;
UINT        size;
NX_MD5      context;

    /* Print out test information banner.  */
    printf("NetX Test:   Utility Test..............................................");

    /* Null string pointer.  */
    status = _nx_utility_string_length_check(NX_NULL, &string_length, 10);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* The length of string is less than max length.  */
    status = _nx_utility_string_length_check("test string", &string_length, sizeof("test string"));

    /* Check status.  */
    if ((status != NX_SUCCESS) || (string_length != sizeof("test string") - 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* The length of string is equal to max length.  */
    status = _nx_utility_string_length_check("test string", &string_length, sizeof("test string") - 1);

    /* Check status.  */
    if ((status != NX_SUCCESS) || (string_length != sizeof("test string") - 1))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* The length of string is equal to max length.  */
    status = _nx_utility_string_length_check("test string", &string_length, sizeof("test string") - 2);

    /* Check status.  */
    if (status == NX_SUCCESS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Verify _nx_utility_string_to_uint().  */

    /* Null string pointer.  */
    status = _nx_utility_string_to_uint(NX_NULL, sizeof("4294967295") -1, &number);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Null string pointer.  */
    status = _nx_utility_string_to_uint("4294967295", sizeof("4294967295") -1, NX_NULL);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Invalid string length.  */
    status = _nx_utility_string_to_uint("4294967295", 0, &number);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Verify string "1234".  */
    status = _nx_utility_string_to_uint("1234", sizeof("1234") -1, &number);

    /* Check status.  */
    if ((status) || (number != 1234))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Verify max value number(Hex:FFFFFFFF, Decimal:4294967295).  */
    status = _nx_utility_string_to_uint("4294967295", sizeof("4294967295") -1, &number);

    /* Check status.  */
    if ((status) || (number != 4294967295))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test invalid string "4294967296".  */
    status = _nx_utility_string_to_uint("4294967296", sizeof("4294967296") -1, &number);

    /* Check status.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test invalid string "4294967300".  */
    status = _nx_utility_string_to_uint("4294967300", sizeof("4294967300") -1, &number);

    /* Check status.  */
    if (status != NX_OVERFLOW)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test invalid string.  */
    status = _nx_utility_string_to_uint("123+", sizeof("123+") -1, &number);

    /* Check status.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test invalid string.  */
    status = _nx_utility_string_to_uint("123A", sizeof("123A") -1, &number);

    /* Check status.  */
    if (status != NX_INVALID_PARAMETERS)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Base64 encode test.  */

    /* Null name pointer.  */
    status = _nx_utility_base64_encode(NX_NULL, sizeof("name:password") -1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* 0 name size.  */
    status = _nx_utility_base64_encode("name:password", 0, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* NULL buffer pointer.  */
    status = _nx_utility_base64_encode("name:password", sizeof("name:password") -1, NX_NULL, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* 0 buffer size.  */
    status = _nx_utility_base64_encode("name:password", sizeof("name:password") -1, out_buffer, 0, &bytes_copied);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* NULL bytes copied pointer.  */
    status = _nx_utility_base64_encode("name:password", sizeof("name:password") -1, out_buffer, sizeof(out_buffer), NX_NULL);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Encode name with small buffer.  */
    status = _nx_utility_base64_encode("name:password", sizeof("name:password") -1, out_buffer, 20, &bytes_copied);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Encode name successfully.  */
    status = _nx_utility_base64_encode("name:password", sizeof("name:password") -1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 20) ||
        (memcmp(out_buffer, "bmFtZTpwYXNzd29yZA==", 20) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Encode special character.  */
    input_buffer[0] = 0x80;
    input_buffer[1] = 0;
    status = _nx_utility_base64_encode(input_buffer, 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 4) ||
        (memcmp(out_buffer, "gA==", 4) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Encode 1 character.  */
    input_buffer[0] = 'a';
    input_buffer[1] = 0;
    status = _nx_utility_base64_encode(input_buffer, 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 4) ||
        (memcmp(out_buffer, "YQ==", 4) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test array without null terminator.  */
    input_buffer[0] = 'a';
    input_buffer[1] = 0xff;
    status = _nx_utility_base64_encode(input_buffer, 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 4) ||
        (memcmp(out_buffer, "YQ==", 4) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Encode 2 characters.  */
    input_buffer[0] = 'a';
    input_buffer[1] = 'b';
    input_buffer[2] = 0;
    status = _nx_utility_base64_encode(input_buffer, 2, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 4) ||
        (memcmp(out_buffer, "YWI=", 4) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Test array without null terminator.  */
    input_buffer[0] = 'a';
    input_buffer[1] = 'b';
    input_buffer[2] = 0xff;
    status = _nx_utility_base64_encode(input_buffer, 2, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 4) ||
        (memcmp(out_buffer, "YWI=", 4) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Crash test.  */
    for (i = 1; i <= 0xFF; i++)
    {
        input_buffer[0] = i;
        input_buffer[1] = i;
        input_buffer[2] = i;
        input_buffer[3] = 0;
        _nx_utility_base64_encode(input_buffer, 3, out_buffer, sizeof(out_buffer), &bytes_copied);
    }

    /* Base64 decode test.  */
    
    /* Null name pointer.  */
    status = _nx_utility_base64_decode(NX_NULL, sizeof("bmFtZTpwYXNzd29yZA==") -1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* 0 name size.  */
    status = _nx_utility_base64_decode("bmFtZTpwYXNzd29yZA==", 0, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* NULL buffer pointer.  */
    status = _nx_utility_base64_decode("bmFtZTpwYXNzd29yZA==", sizeof("bmFtZTpwYXNzd29yZA==") -1, NX_NULL, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* 0 buffer size.  */
    status = _nx_utility_base64_decode("bmFtZTpwYXNzd29yZA==", sizeof("bmFtZTpwYXNzd29yZA==") -1, out_buffer, 0, &bytes_copied);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* NULL bytes copied pointer.  */
    status = _nx_utility_base64_decode("bmFtZTpwYXNzd29yZA==", sizeof("bmFtZTpwYXNzd29yZA==") -1, out_buffer, sizeof(out_buffer), NX_NULL);

    /* Check status.  */
    if (status != NX_PTR_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }
    
    /* Encode name with small buffer.  */
    status = _nx_utility_base64_decode("bmFtZTpwYXNzd29yZA==", sizeof("bmFtZTpwYXNzd29yZA==") -1, out_buffer, 13, &bytes_copied);

    /* Check status.  */
    if (status != NX_SIZE_ERROR)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Encode name successfully.  */
    status = _nx_utility_base64_decode("bmFtZTpwYXNzd29yZA==", sizeof("bmFtZTpwYXNzd29yZA==") -1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 13) ||
        (memcmp(out_buffer, "name:password", 13) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Encode special character.  */
    status = _nx_utility_base64_decode("gA==", sizeof("gA==") - 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 1) ||
        (out_buffer[0] != 0x80))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Decode cut string.  */
    status = _nx_utility_base64_decode("bmFt=TpwYXNzd29yZA==", sizeof("bmFt=TpwYXNzd29yZA==") -1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 3) ||
        (memcmp(out_buffer, "nam", 3) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Decode cut string.  */
    status = _nx_utility_base64_decode("bmFt\0TpwYXNzd29yZA==", sizeof("bmFt\0TpwYXNzd29yZA==") -1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if ((status != NX_SUCCESS) || 
        (bytes_copied != 3) ||
        (memcmp(out_buffer, "nam", 3) != 0))
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    /* Crash test.  */
    for (i = 1; i <= 0xFF; i++)
    {
        input_buffer[0] = i;
        input_buffer[1] = i;
        input_buffer[2] = i;
        input_buffer[3] = 0;
        _nx_utility_base64_decode(input_buffer, 3, out_buffer, sizeof(out_buffer), &bytes_copied);
    }

    /* Read overflow test.  */
    input_buffer[0] = '=';
    input_buffer[1] = '=';
    input_buffer[2] = 0;
    status = _nx_utility_base64_decode(&input_buffer[1], 1, out_buffer, 0xffffffff, &bytes_copied);

    /* Check status.  */
    if (status || bytes_copied != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_utility_base64_decode("==", sizeof("==") - 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status || bytes_copied != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_utility_base64_decode("T", sizeof("T") - 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status || bytes_copied != 0)
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_utility_base64_decode("TQ", sizeof("TQ") - 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status || bytes_copied != 1 || out_buffer[0] != 'M')
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_utility_base64_decode("TQ=", sizeof("TQ=") - 1, out_buffer, sizeof(out_buffer), &bytes_copied);

    /* Check status.  */
    if (status || bytes_copied != 1 || out_buffer[0] != 'M')
    {

        printf("ERROR!\n");
        test_control_return(1);
    }

    number = 0x1234;
    size = _nx_utility_uint_to_string(number, 10, out_buffer, sizeof(out_buffer));
    if ((size != 4) || (memcmp(out_buffer, "4660", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 16, out_buffer, sizeof(out_buffer));
    if ((size != 4) || (memcmp(out_buffer, "1234", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 8, out_buffer, sizeof(out_buffer));
    if ((size != 5) || (memcmp(out_buffer, "11064", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    number = 0xffffffff;
    size = _nx_utility_uint_to_string(number, 10, out_buffer, sizeof(out_buffer));
    if ((size != 10) || (memcmp(out_buffer, "4294967295", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 16, out_buffer, sizeof(out_buffer));
    if ((size != 8) || (memcmp(out_buffer, "ffffffff", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 8, out_buffer, sizeof(out_buffer));
    if ((size != 11) || (memcmp(out_buffer, "37777777777", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    number = 0;
    size = _nx_utility_uint_to_string(number, 10, out_buffer, sizeof(out_buffer));
    if ((size != 1) || (memcmp(out_buffer, "0", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 16, out_buffer, sizeof(out_buffer));
    if ((size != 1) || (memcmp(out_buffer, "0", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 8, out_buffer, sizeof(out_buffer));
    if ((size != 1) || (memcmp(out_buffer, "0", size) != 0))
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    number = 0xffffffff;
    size = _nx_utility_uint_to_string(number, 16, out_buffer, 8);
    if (size != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 10, NX_NULL, 8);
    if (size != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 10, out_buffer, 0);
    if (size != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    size = _nx_utility_uint_to_string(number, 0, out_buffer, sizeof(out_buffer));
    if (size != 0)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_md5_initialize(NX_NULL);
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_md5_update(NX_NULL, input_buffer, 1);
    if (status != NX_PTR_ERROR)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    status = _nx_md5_update(&context, input_buffer, 0);
    if (status)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    _nx_md5_initialize(&context);
    context.nx_md5_bit_count[0] = 0xffffffff;

    status = _nx_md5_update(&context, input_buffer, 1);
    if (status || context.nx_md5_bit_count[1] != 1)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }

    printf("SUCCESS!\n");
    test_control_return(0);
}

