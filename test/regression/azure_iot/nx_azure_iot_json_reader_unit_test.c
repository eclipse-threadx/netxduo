/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>  /* macros: https://api.cmocka.org/group__cmocka__asserts.html */

#include "nx_api.h"
#include "nx_azure_iot.h"
#include "nx_azure_iot_ciphersuites.h"
#include "nx_azure_iot_json_reader.h"

#define DEMO_DHCP_DISABLE
#define DEMO_IPV4_ADDRESS         IP_ADDRESS(192, 168, 100, 33)
#define DEMO_IPV4_MASK            0xFFFFFF00UL
#define DEMO_GATEWAY_ADDRESS      IP_ADDRESS(192, 168, 100, 1)
#define DEMO_DNS_SERVER_ADDRESS   IP_ADDRESS(192, 168, 100, 1)
#define NETWORK_DRIVER            _nx_ram_network_driver

/* Include main.c in the test case since we need to disable DHCP in this test. */
#include "main.c"

#define STRING_UNSIGNED_ARGS(s)                     (UCHAR *)s, strlen(s)

typedef VOID (*NX_AZURE_TEST_FN)();

static NX_IP *g_ip_ptr;
static NX_PACKET_POOL *g_pool_ptr;
static NX_DNS *g_dns_ptr;
static ULONG g_available_packet;

static const CHAR test_sample_json[] = "{\
\"uint_id\":1,\
\"int_value\":-56,\
\"double_value\":1234,\
\"bool_value1\":true,\
\"bool_value2\":false,\
\"description\":\"Unit test sample json\",\
\"list_value\":[1,1,\"unit test\",null],\
\"object_value\":{\"test\":true},\
\"json_value\":{\"test2\":true}\
}";

static UINT generate_test_sample_json(NX_PACKET *packet_ptr, UINT number_of_obj)
{
UINT status;

    if (number_of_obj > 1)
    {
        if ((status = nx_packet_data_append(packet_ptr, STRING_UNSIGNED_ARGS("["),
                                            packet_ptr -> nx_packet_pool_owner, NX_WAIT_FOREVER)))
        {
           return(status);
        }
    }
    

    for (UINT index = 0; index < number_of_obj; index++)
    {
        if (index != 0)
        {
            if ((status = nx_packet_data_append(packet_ptr, STRING_UNSIGNED_ARGS(","),
                                                packet_ptr -> nx_packet_pool_owner, NX_WAIT_FOREVER)))
            {
                return(status);
            }
        }

        if ((status = nx_packet_data_append(packet_ptr, STRING_UNSIGNED_ARGS(test_sample_json),
                                            packet_ptr -> nx_packet_pool_owner, NX_WAIT_FOREVER)))
        {
            return(status);
        }
    }

    if (number_of_obj > 1)
    {  
        if ((status = nx_packet_data_append(packet_ptr, STRING_UNSIGNED_ARGS("]"),
                                            packet_ptr -> nx_packet_pool_owner, NX_WAIT_FOREVER)))
        {
           return(status);
        }
    }
    
    return(NX_AZURE_IOT_SUCCESS);
}

static UINT read_test_sample_json(NX_AZURE_IOT_JSON_READER *reader_ptr, UINT number_of_obj)
{
UINT status;
uint32_t uint_value;
int32_t int_value;
UINT bool_value;
double double_value;
UCHAR str_value[100];
UINT bytes_copied;

    if (number_of_obj > 1)
    {
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_BEGIN_ARRAY)
        {
            return(NX_AZURE_IOT_FAILURE);
        }
    }


    for (UINT index = 0; index < number_of_obj; index++)
    {
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_BEGIN_OBJECT)
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* uint_id = 1 */
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("uint_id")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_uint32_get(reader_ptr, &uint_value) ||
            uint_value != 1)
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* int_value = 1 */
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("int_value")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_int32_get(reader_ptr, &int_value) ||
            int_value != -56)
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* double_value = 1234 */
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("double_value")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_double_get(reader_ptr, &double_value) ||
            double_value != 1234.0)
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* bool_value1 = true */
        bool_value = 0x11111111;
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("bool_value1")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_bool_get(reader_ptr, &bool_value) ||
            (bool_value != NX_TRUE))
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* bool_value2 = false */
        bool_value = 0x11111111;
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("bool_value2")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_bool_get(reader_ptr, &bool_value) ||
            (bool_value != NX_FALSE))
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* description = Unit test sample json */
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("description")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_string_get(reader_ptr, str_value,
                                                      sizeof(str_value), &bytes_copied) ||
            memcmp(str_value, STRING_UNSIGNED_ARGS("Unit test sample json") != 0))
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* list_value = [1,1,\"unit test\",null] */
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("list_value")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_BEGIN_ARRAY)
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_int32_get(reader_ptr, &int_value) ||
            int_value != 1 ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_next_token(reader_ptr))
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* object_value:{"test":true} */
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("object_value")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_BEGIN_OBJECT ||
            nx_azure_iot_json_reader_skip_children(reader_ptr))
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        /* object_value:{"test2":true} */
        bool_value = 0x11111111;
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("json_value")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_BEGIN_OBJECT ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            !nx_azure_iot_json_reader_token_is_text_equal(reader_ptr, STRING_UNSIGNED_ARGS("test2")) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_bool_get(reader_ptr, &bool_value) ||
            (bool_value != NX_TRUE) ||
            nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_END_OBJECT)
        {
            return(NX_AZURE_IOT_FAILURE);
        }

        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_END_OBJECT)
        {
            return(NX_AZURE_IOT_FAILURE);
        }
    }

    if (number_of_obj > 1)
    {
        if (nx_azure_iot_json_reader_next_token(reader_ptr) ||
            nx_azure_iot_json_reader_token_type(reader_ptr) != NX_AZURE_IOT_READER_TOKEN_END_ARRAY)
        {
            return(NX_AZURE_IOT_FAILURE);
        }
    }

    return(NX_AZURE_IOT_SUCCESS);
}

/* Hook executed before every test */
static VOID test_begin()
{
    /* Record number of available packet before test */
    g_available_packet = g_pool_ptr -> nx_packet_pool_available;
}

/* Hook execute after all tests are executed successfully */
static VOID test_end()
{

    /* Check if all the packet are released */
    assert_int_equal(g_pool_ptr -> nx_packet_pool_available, g_available_packet);
}

/**
 * Test json reader INVALID argument
 *
 **/
static VOID test_nx_azure_iot_json_reader_invalid_argument_fail()
{
NX_AZURE_IOT_JSON_READER reader;

    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_json_reader_with_buffer_init(NX_NULL,
                                                              NX_NULL, 0),
    					 NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_reader_with_buffer_init(&reader,
                                                              NX_NULL, 0),
    					 NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_init(NX_NULL, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_init(&reader, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_deinit(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_next_token(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_skip_children(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_token_bool_get(NX_NULL, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_token_uint32_get(NX_NULL, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_token_int32_get(NX_NULL, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_token_double_get(NX_NULL, NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_reader_token_string_get(NX_NULL,
                                                                   NX_NULL, 0,
                                                                   NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_reader_token_is_text_equal(NX_NULL, NX_NULL, 0),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_reader_token_type(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json reader empty payload
 *
 **/
static VOID test_nx_azure_iot_json_reader_empty_fail()
{
NX_AZURE_IOT_JSON_READER reader;
NX_PACKET *packet_ptr;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_azure_iot_json_reader_with_buffer_init(&reader,
                                                               test_sample_json,
                                                               0),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_reader_next_token(&reader), NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_deinit(&reader),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_packet_allocate(g_pool_ptr,
                                        &packet_ptr, 0,
                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader,
                                                   packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_reader_next_token(&reader), NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);
                     
    assert_int_equal(nx_azure_iot_json_reader_deinit(&reader),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json reader static buffer
 *
 **/
static VOID test_nx_azure_iot_json_reader_success()
{
NX_AZURE_IOT_JSON_READER reader;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_azure_iot_json_reader_with_buffer_init(&reader,
                                                               test_sample_json,
                                                               sizeof(test_sample_json) - 1),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(read_test_sample_json(&reader, 1), NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_json_reader_next_token(&reader), NX_AZURE_IOT_NOT_FOUND);

    assert_int_equal(nx_azure_iot_json_reader_deinit(&reader),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json reader with nx_packet
 *
 **/
static VOID test_nx_azure_iot_json_reader_with_nx_packet_success()
{
NX_AZURE_IOT_JSON_READER reader;
NX_PACKET *packet_ptr;
UINT number_of_obj = ((g_pool_ptr -> nx_packet_pool_payload_size * NX_AZURE_IOT_READER_MAX_LIST) /
                       (sizeof(test_sample_json) - 1)) - 1;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_packet_allocate(g_pool_ptr,
                                        &packet_ptr, 0,
                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_sample_json(packet_ptr, number_of_obj),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_init(&reader,
                                                   packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(read_test_sample_json(&reader, number_of_obj), NX_AZURE_IOT_SUCCESS);
    assert_int_equal(nx_azure_iot_json_reader_next_token(&reader), NX_AZURE_IOT_NOT_FOUND);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_deinit(&reader),
                     NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json reader with OOM
 *
 **/
static VOID test_nx_azure_iot_json_reader_with_oom_fail()
{
NX_AZURE_IOT_JSON_READER reader;
NX_PACKET *packet_ptr;
UINT number_of_obj = ((g_pool_ptr -> nx_packet_pool_payload_size * NX_AZURE_IOT_READER_MAX_LIST) /
                       (sizeof(test_sample_json) - 1)) + 1;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_packet_allocate(g_pool_ptr,
                                        &packet_ptr, 0,
                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_sample_json(packet_ptr, number_of_obj),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_reader_init(&reader,
                                                       packet_ptr),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_reader_deinit(&reader),
                     NX_AZURE_IOT_SUCCESS);
}

VOID demo_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr,
                UINT (*unix_time_callback)(ULONG *unix_time))
{
NX_AZURE_TEST_FN tests[] = { test_nx_azure_iot_json_reader_invalid_argument_fail,
                             test_nx_azure_iot_json_reader_empty_fail,
                             test_nx_azure_iot_json_reader_success,
                             test_nx_azure_iot_json_reader_with_nx_packet_success,
                             test_nx_azure_iot_json_reader_with_oom_fail };
INT number_of_tests =  sizeof(tests)/sizeof(tests[0]);

    printf("Number of tests %d\r\n", number_of_tests);

    g_ip_ptr = ip_ptr;
    g_pool_ptr = pool_ptr;
    g_dns_ptr = dns_ptr;

    for (INT index = 0; index < number_of_tests; index++)
    {
        test_begin();
        tests[index]();
        test_end();
    }
}
