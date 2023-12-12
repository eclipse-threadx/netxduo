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
#include "nx_azure_iot_json_writer.h"

#define DEMO_DHCP_DISABLE
#define DEMO_IPV4_ADDRESS         IP_ADDRESS(192, 168, 100, 33)
#define DEMO_IPV4_MASK            0xFFFFFF00UL
#define DEMO_GATEWAY_ADDRESS      IP_ADDRESS(192, 168, 100, 1)
#define DEMO_DNS_SERVER_ADDRESS   IP_ADDRESS(192, 168, 100, 1)
#define NETWORK_DRIVER            _nx_ram_network_driver

/* Include main.c in the test case since we need to disable DHCP in this test. */
#include "main.c"

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE                             1500 * 11
#endif /* MAX_BUFFER_SIZE */

#define DOUBLE_DECIMAL_PLACE_DIGITS                 2
#define STRING_UNSIGNED_ARGS(s)                     (UCHAR *)s, strlen(s)

typedef VOID (*NX_AZURE_TEST_FN)();

static const CHAR test_sample_json[] = "{\
\"id\":1,\
\"value\":1234,\
\"description\":\"Unit test sample json\",\
\"list_value\":[1,1,\"unit test\",null],\
\"object_value\":{\"test\":true},\
\"json_value\":{\"test2\":true}\
}";

static NX_IP *g_ip_ptr;
static NX_PACKET_POOL *g_pool_ptr;
static NX_DNS *g_dns_ptr;
static ULONG g_available_packet;
static UCHAR g_scratch_buffer[MAX_BUFFER_SIZE];

static UINT generate_test_sample_json(NX_AZURE_IOT_JSON_WRITER *writer_ptr, UINT number_of_obj)
{
UINT status;

    if ((status = nx_azure_iot_json_writer_append_begin_array(writer_ptr)))
    {
        return(status);
    }

    for (UINT index = 0; index < number_of_obj; index++)
    {
        if ((status = nx_azure_iot_json_writer_append_begin_object(writer_ptr)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_with_int32_value(writer_ptr,
                                                                                STRING_UNSIGNED_ARGS("id"), 1)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_with_double_value(writer_ptr,
                                                                                 STRING_UNSIGNED_ARGS("value"),
                                                                                 1234.0, DOUBLE_DECIMAL_PLACE_DIGITS)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_with_string_value(writer_ptr,
                                                                                 STRING_UNSIGNED_ARGS("description"),
                                                                                 STRING_UNSIGNED_ARGS("Unit test sample json"))))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_name(writer_ptr, STRING_UNSIGNED_ARGS("list_value"))))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_begin_array(writer_ptr)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_int32(writer_ptr, 1)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_double(writer_ptr, 1.0, DOUBLE_DECIMAL_PLACE_DIGITS)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_string(writer_ptr, STRING_UNSIGNED_ARGS("unit test"))))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_null(writer_ptr)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_end_array(writer_ptr)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_name(writer_ptr, STRING_UNSIGNED_ARGS("object_value"))))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_begin_object(writer_ptr)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_with_bool_value(writer_ptr, STRING_UNSIGNED_ARGS("test"), 1)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_end_object(writer_ptr)))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_property_name(writer_ptr, STRING_UNSIGNED_ARGS("json_value"))))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_json_text(writer_ptr, STRING_UNSIGNED_ARGS("{\"test2\":true}"))))
        {
            return(status);
        }

        if ((status = nx_azure_iot_json_writer_append_end_object(writer_ptr)))
        {
            return(status);
        }
    }

    if ((status = nx_azure_iot_json_writer_append_end_array(writer_ptr)))
    {
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT copy_nx_packet_json_to_buffer(NX_AZURE_IOT_JSON_WRITER *writer_ptr, ULONG offset,
                                          UCHAR *buffer, UINT buffer_size, ULONG *bytes_copied)
{
NX_PACKET *packet_ptr = writer_ptr -> packet_ptr;
UINT status;

    *bytes_copied = 0;
    if (packet_ptr == NX_NULL)
    {
        return(NX_AZURE_IOT_SUCCESS);
    }

    if ((status = nx_packet_data_extract_offset(packet_ptr, offset, buffer,
                                                buffer_size, bytes_copied)))
    {
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

/* Hook executed before every test */
static VOID test_begin()
{
    memset(g_scratch_buffer, 0, sizeof(g_scratch_buffer));

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
 * Test json writer INVALID argument
 *
 **/
static VOID test_nx_azure_iot_json_writer_invalid_argument_fail()
{
    printf("test starts =>: %s\n", __func__);

    assert_int_not_equal(nx_azure_iot_json_writer_init(NX_NULL,
                                                       NX_NULL,
                                                       NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_with_buffer_init(NX_NULL,
                                                                   NX_NULL,
                                                                   0),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_deinit(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_property_with_int32_value(NX_NULL,
                                                                                   STRING_UNSIGNED_ARGS("fake"),
                                                                                   1),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_property_with_double_value(NX_NULL,
                                                                                    STRING_UNSIGNED_ARGS("fake"),
                                                                                    1, DOUBLE_DECIMAL_PLACE_DIGITS),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_property_with_bool_value(NX_NULL,
                                                             STRING_UNSIGNED_ARGS("fake"),
                                                             1),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_property_with_string_value(NX_NULL,
                                                               STRING_UNSIGNED_ARGS("fake"),
                                                               STRING_UNSIGNED_ARGS("fake_value")),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_writer_get_bytes_used(NX_NULL),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_writer_append_string(NX_NULL,
                                                                STRING_UNSIGNED_ARGS("fake_value")),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_json_text(NX_NULL,
                                                                   STRING_UNSIGNED_ARGS("fake_value")),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_property_name(NX_NULL,
                                                                       STRING_UNSIGNED_ARGS("fake_value")),
                         NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_bool(NX_NULL, 1), NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_int32(NX_NULL, 1), NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_double(NX_NULL,
                                                                1, DOUBLE_DECIMAL_PLACE_DIGITS),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(nx_azure_iot_json_writer_append_null(NX_NULL), NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_begin_object(NX_NULL), NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_begin_array(NX_NULL), NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_end_object(NX_NULL), NX_AZURE_IOT_SUCCESS);
    assert_int_not_equal(nx_azure_iot_json_writer_append_end_array(NX_NULL), NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json writer static buffer
 *
 **/
static VOID test_nx_azure_iot_json_writer_success()
{
NX_AZURE_IOT_JSON_WRITER writer;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_azure_iot_json_writer_with_buffer_init(&writer,
                                                               g_scratch_buffer,
                                                               sizeof(g_scratch_buffer)),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(generate_test_sample_json(&writer, 1), NX_AZURE_IOT_SUCCESS);

    assert_memory_equal(g_scratch_buffer + 1, test_sample_json, sizeof(test_sample_json) - 1);

    assert_int_equal(nx_azure_iot_json_writer_deinit(&writer),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json writer with nx_packet
 *
 **/
static VOID test_nx_azure_iot_json_writer_with_nx_packet_success()
{
NX_AZURE_IOT_JSON_WRITER writer;
NX_PACKET *packet_ptr;
ULONG bytes_copied;
UCHAR *start_ptr;

    printf("test starts =>: %s\n", __func__);

    for (INT number_of_obj = 1; number_of_obj <= 100; number_of_obj++)
    {
        assert_int_equal(nx_packet_allocate(g_pool_ptr,
                                            &packet_ptr, 0,
                                            NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_json_writer_init(&writer,
                                                       packet_ptr,
                                                       NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(generate_test_sample_json(&writer, number_of_obj),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(copy_nx_packet_json_to_buffer(&writer, 0,
                                                       g_scratch_buffer,
                                                       sizeof(g_scratch_buffer),
                                                       &bytes_copied),
                         NX_AZURE_IOT_SUCCESS);

        start_ptr = g_scratch_buffer + 1;
        for (INT index = 0; index < number_of_obj; index++)
        {
            assert_memory_equal(start_ptr,
                                test_sample_json, (sizeof(test_sample_json) - 1));
            start_ptr += sizeof(test_sample_json);
        }

        assert_int_equal(nx_packet_release(packet_ptr),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_json_writer_deinit(&writer),
                         NX_AZURE_IOT_SUCCESS);
    }
}

/**
 * Test json writer when reached out of memory
 *
 **/
static VOID test_nx_azure_iot_json_writer_with_nx_packet_oom_fail()
{
NX_AZURE_IOT_JSON_WRITER writer;
NX_PACKET *packet_ptr;
UINT number_of_obj = (g_pool_ptr -> nx_packet_pool_size / (sizeof(test_sample_json) - 1)) + 1;

    printf("test starts =>: %s\n", __func__);

    assert_int_equal(nx_packet_allocate(g_pool_ptr,
                                        &packet_ptr, 0,
                                        NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_writer_init(&writer,
                                                   packet_ptr,
                                                   NX_NO_WAIT),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_not_equal(generate_test_sample_json(&writer, number_of_obj),
                         NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_packet_release(packet_ptr),
                     NX_AZURE_IOT_SUCCESS);

    assert_int_equal(nx_azure_iot_json_writer_deinit(&writer),
                         NX_AZURE_IOT_SUCCESS);
}

/**
 * Test json writer with offset nx_packet
 *
 **/
static VOID test_nx_azure_iot_json_writer_with_nx_packet_offset_success()
{
NX_AZURE_IOT_JSON_WRITER writer;
NX_PACKET *packet_ptr;
ULONG bytes_copied;
UCHAR *start_ptr;
UINT number_of_obj = 60;

    printf("test starts =>: %s\n", __func__);

    for (INT offset = 1; offset <= (2 * g_pool_ptr -> nx_packet_pool_payload_size); offset++)
    {
        assert_int_equal(nx_packet_allocate(g_pool_ptr,
                                            &packet_ptr, 0,
                                            NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

        /* append data till offset */
        assert_int_equal(nx_packet_data_append(packet_ptr,
                                               g_scratch_buffer,
                                               offset, g_pool_ptr,
                                               NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_json_writer_init(&writer,
                                                       packet_ptr,
                                                       NX_WAIT_FOREVER),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(generate_test_sample_json(&writer, number_of_obj),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(copy_nx_packet_json_to_buffer(&writer, offset,
                                                       g_scratch_buffer,
                                                       sizeof(g_scratch_buffer),
                                                       &bytes_copied),
                         NX_AZURE_IOT_SUCCESS);

        start_ptr = g_scratch_buffer + 1;
        for (INT index = 0; index < number_of_obj; index++)
        {
            assert_memory_equal(start_ptr,
                                test_sample_json, (sizeof(test_sample_json) - 1));
            start_ptr += sizeof(test_sample_json);
        }

        assert_int_equal(nx_packet_release(packet_ptr),
                         NX_AZURE_IOT_SUCCESS);

        assert_int_equal(nx_azure_iot_json_writer_deinit(&writer),
                         NX_AZURE_IOT_SUCCESS);
    }
}

VOID demo_entry(NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr,
                UINT (*unix_time_callback)(ULONG *unix_time))
{
NX_AZURE_TEST_FN tests[] = { test_nx_azure_iot_json_writer_invalid_argument_fail,
                             test_nx_azure_iot_json_writer_success,
                             test_nx_azure_iot_json_writer_with_nx_packet_success,
                             test_nx_azure_iot_json_writer_with_nx_packet_oom_fail,
                             test_nx_azure_iot_json_writer_with_nx_packet_offset_success };
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
