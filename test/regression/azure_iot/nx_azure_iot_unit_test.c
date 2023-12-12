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
#include "nx_crypto_aes.h"
#include "nx_websocket_client.h"

#define DEMO_DHCP_DISABLE
#define DEMO_IPV4_ADDRESS         IP_ADDRESS(192, 168, 100, 33)
#define DEMO_IPV4_MASK            0xFFFFFF00UL
#define DEMO_GATEWAY_ADDRESS      IP_ADDRESS(192, 168, 100, 1)
#define DEMO_DNS_SERVER_ADDRESS   IP_ADDRESS(192, 168, 100, 1)
#define NETWORK_DRIVER            _nx_ram_network_driver

/* Include main.c in the test case since we need to disable DHCP in this test. */
#include "main.c"

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE                             1500
#endif /* MAX_BUFFER_SIZE */

typedef VOID (*NX_AZURE_TEST_FN)();

static UCHAR metadata_buffer[NX_AZURE_IOT_TLS_METADATA_BUFFER_SIZE];
static UCHAR buffer[MAX_BUFFER_SIZE] = { 0 };

static CHAR *g_url_encoded_hmac_sha256_data_set[][3] = {
{ "De1TOYsqBULq0nSzjVWvjCYUnQ3pklTuUdmoLsleyaw=",
  "0ne000A247E/registrations/test1\n1587103748",
  "mU63otlyFYT+ATVO9mM0g81c3CQ5fmr0DrviGG2wX0Q=" },
{ "j07p2UdpIZn/Y+WvdCf8j3KVio2PqOAc55f3aERGtUE=",
  "0ne000A247E/registrations/test1\n1587103748",
  "/kZa770GiwCyGVtcPL0KoCRAKqeF2NxXWUrhB4pkOSQ=" },
{ "j07p2UdpIZn/Y+WvdCf8j3KVio2PqOAc55f3aERGtUE=",
  "0ne000A247E/registrations/test4\n1587103748",
  "3Iv4Y9dPmTc24ETg/5wr2AZ66s10sGig6mah93R6IB4=" }
};
static UINT log_index = 0;

static VOID test_log_reset()
{
    log_index = 0;
    memset(buffer, 0, sizeof(buffer));
}

static VOID test_log_callback(az_log_classification classification, UCHAR *msg, UINT msg_len)
{
    if ((classification == AZ_LOG_IOT_AZURERTOS) && ((log_index + msg_len) <= MAX_BUFFER_SIZE))
    {
        memcpy((VOID *)(buffer + log_index), (VOID *)msg, msg_len);
        log_index += msg_len;
    }
}

/**
 * Test base64 decoding
 *
 **/
static VOID test_nx_azure_iot_url_encoded_hmac_sha256_calculate_success()
{
UCHAR *output_ptr;
UINT output_len;
UINT status;
INT number_of_data_set =  sizeof(g_url_encoded_hmac_sha256_data_set)/sizeof(g_url_encoded_hmac_sha256_data_set[0]);
NX_AZURE_IOT_RESOURCE resource;

    printf("test starts =>: %s\n", __func__);

    resource.resource_crypto_array = _nx_azure_iot_tls_supported_crypto;
    resource.resource_crypto_array_size = _nx_azure_iot_tls_supported_crypto_size;
    resource.resource_cipher_map = _nx_azure_iot_tls_ciphersuite_map;
    resource.resource_cipher_map_size = _nx_azure_iot_tls_ciphersuite_map_size;
    resource.resource_metadata_ptr = metadata_buffer;
    resource.resource_metadata_size = sizeof(metadata_buffer);

    for (INT index = 0; index < number_of_data_set; index++)
    {
        status = nx_azure_iot_base64_hmac_sha256_calculate(&resource,
                                                           g_url_encoded_hmac_sha256_data_set[index][0],
                                                           strlen(g_url_encoded_hmac_sha256_data_set[index][0]),
                                                           g_url_encoded_hmac_sha256_data_set[index][1],
                                                           strlen(g_url_encoded_hmac_sha256_data_set[index][1]),
                                                           buffer, sizeof(buffer), &output_ptr, &output_len);
        assert_int_equal(status, NX_AZURE_IOT_SUCCESS);
        assert_memory_equal(g_url_encoded_hmac_sha256_data_set[index][2], output_ptr,
                            strlen(g_url_encoded_hmac_sha256_data_set[index][2]));
    }
}

/**
 * Test function nx_azure_iot_publish_packet_get
 *
 **/
extern NX_CRYPTO_METHOD crypto_method_tls_prf_sha256;
static NXD_MQTT_CLIENT mqtt_client;
static NX_SECURE_TLS_CIPHERSUITE_INFO test_ciphersuite = {TLS_NULL_WITH_NULL_NULL, NX_NULL, NX_NULL, NX_NULL, 0, 0, NX_NULL, 0, NX_NULL};
static NX_CRYPTO_METHOD session_method;
static NX_SECURE_TLS_CRYPTO test_crypto_table =
{
    /* Ciphersuite lookup table and size. */
    &test_ciphersuite,
    1,
#ifndef NX_SECURE_DISABLE_X509
    /* X.509 certificate cipher table and size. */
    NX_NULL,
    0,
#endif
    /* TLS version-specific methods. */
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    NX_NULL,
    NX_NULL,
    &crypto_method_tls_prf_1,
#endif

#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
    NX_NULL,
    &crypto_method_tls_prf_sha256,
#endif

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
    &crypto_method_hkdf,
    &crypto_method_hmac,
    &crypto_method_ecdhe,
#endif
};

static VOID test_nx_azure_iot_publish_packet_get()
{
NX_AZURE_IOT *nx_azure_iot_ptr;
NX_PACKET *packet_ptr;


    /* ---- Test preparation ---- */
    mqtt_client.nxd_mqtt_client_ip_ptr = &ip_0;
    mqtt_client.nxd_mqtt_client_packet_pool_ptr = &pool_0;
    mqtt_client.nxd_mqtt_client_use_websocket = NX_FALSE;
    mqtt_client.nxd_mqtt_client_use_tls = NX_FALSE;
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_id = NX_SECURE_TLS_ID;
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_tcp_socket = &(mqtt_client.nxd_mqtt_client_socket);
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_local_session_active = NX_TRUE;
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_session_ciphersuite = &test_ciphersuite;
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_crypto_table = &test_crypto_table;
    test_ciphersuite.nx_secure_tls_session_cipher = &session_method;
    session_method.nx_crypto_algorithm = NX_CRYPTO_ENCRYPTION_AES_CBC;
    session_method.nx_crypto_IV_size_in_bits = NX_CRYPTO_AES_IV_LEN_IN_BITS;
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_protocol_version = NX_SECURE_TLS_VERSION_TLS_1_2;
    assert_int_equal(nx_tcp_socket_create(mqtt_client.nxd_mqtt_client_ip_ptr, &(mqtt_client.nxd_mqtt_client_socket), "test_client",
                                          NX_IP_NORMAL, NX_DONT_FRAGMENT, 0x80, NXD_MQTT_CLIENT_SOCKET_WINDOW_SIZE, NX_NULL, NX_NULL),
                     NX_SUCCESS);

    /* Test 1: websocket disabled, tls disabled, use ipv4. */
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_IPv4_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* Test 2: websocket disabled, tls disabled, use ipv6. */
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_IPv6_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* Test 3: websocket disabled, tls enabled, use ipv4. */
    mqtt_client.nxd_mqtt_client_use_tls = NX_TRUE;
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_tcp_socket -> nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_SECURE_TLS_RECORD_HEADER_SIZE - (NX_CRYPTO_AES_IV_LEN_IN_BITS >> 3) -
                                                       NX_IPv4_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* Test 4: websocket disabled, tls enabled, use ipv6. */
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_SECURE_TLS_RECORD_HEADER_SIZE - (NX_CRYPTO_AES_IV_LEN_IN_BITS >> 3) -
                                                       NX_IPv6_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* ---- Disable TLS again, and then enable websocket ---- */
    mqtt_client.nxd_mqtt_client_use_tls = NX_FALSE;
    mqtt_client.nxd_mqtt_client_use_websocket = NX_TRUE;
    assert_int_equal(nx_websocket_client_create(&mqtt_client.nxd_mqtt_client_websocket, "Test websocket client", &ip_0, &pool_0),
                     NX_SUCCESS);
    mqtt_client.nxd_mqtt_client_websocket.nx_websocket_client_socket_ptr = &(mqtt_client.nxd_mqtt_client_socket);

    /* Test 5: websocket enabled, tls disabled, use ipv4. */
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_WEBSOCKET_HEADER_SIZE -
                                                       NX_IPv4_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* Test 6: websocket enabled, tls disabled, use ipv6. */
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_WEBSOCKET_HEADER_SIZE -
                                                       NX_IPv6_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* Test 7: websocket enabled, tls enabled, use ipv4. */
    mqtt_client.nxd_mqtt_client_use_tls = NX_TRUE;
    mqtt_client.nxd_mqtt_client_websocket.nx_websocket_client_use_tls = NX_TRUE;
    mqtt_client.nxd_mqtt_client_websocket.nx_websocket_client_tls_session_ptr = &(mqtt_client.nxd_mqtt_tls_session);
    mqtt_client.nxd_mqtt_tls_session.nx_secure_tls_tcp_socket -> nx_tcp_socket_state = NX_TCP_ESTABLISHED;
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V4;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_WEBSOCKET_HEADER_SIZE -
                                                       NX_SECURE_TLS_RECORD_HEADER_SIZE - (NX_CRYPTO_AES_IV_LEN_IN_BITS >> 3) -
                                                       NX_IPv4_TCP_PACKET));
    nx_packet_release(packet_ptr);

    /* Test 8: websocket enabled, tls enabled, use ipv6. */
    mqtt_client.nxd_mqtt_client_socket.nx_tcp_socket_connect_ip.nxd_ip_version = NX_IP_VERSION_V6;
    assert_int_equal(nx_azure_iot_publish_packet_get(NX_NULL, &mqtt_client, &packet_ptr, NX_WAIT_FOREVER),
                     NX_AZURE_IOT_SUCCESS);
    assert_true(packet_ptr -> nx_packet_data_start == (packet_ptr -> nx_packet_prepend_ptr -
                                                       NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET -
                                                       NX_WEBSOCKET_HEADER_SIZE -
                                                       NX_SECURE_TLS_RECORD_HEADER_SIZE - (NX_CRYPTO_AES_IV_LEN_IN_BITS >> 3) -
                                                       NX_IPv6_TCP_PACKET));
    nx_packet_release(packet_ptr);
}

/**
 * Test logging
 *
 **/
static VOID test_nx_azure_iot_log_success()
{
static const CHAR log_message_ptr[] = "[INFO] hello world 1";

    nx_azure_iot_log_init(test_log_callback);

#ifndef AZ_NO_LOGGING
    test_log_reset();
    nx_azure_iot_log(LogLiteralArgs("[INFO]"), LogLiteralArgs(" hello world 1"));
    assert_memory_equal(log_message_ptr, buffer, sizeof(log_message_ptr) - 1);

    test_log_reset();
    nx_azure_iot_log(LogLiteralArgs("[INFO]"), LogLiteralArgs(" hello world %d"), 1);
    assert_memory_equal(log_message_ptr, buffer, sizeof(log_message_ptr) - 1);

    test_log_reset();
    nx_azure_iot_log(LogLiteralArgs("[INFO]"), LogLiteralArgs(" hello %s"), LogLiteralArgs("world 1"));
    assert_memory_equal(log_message_ptr, buffer, sizeof(log_message_ptr) - 1);
#endif /* AZ_NO_LOGGING */
}

VOID demo_entry(NX_IP* ip_ptr, NX_PACKET_POOL* pool_ptr, NX_DNS* dns_ptr, UINT (*unix_time_callback)(ULONG *unix_time))
{
NX_AZURE_TEST_FN tests[] = { test_nx_azure_iot_url_encoded_hmac_sha256_calculate_success,
                             test_nx_azure_iot_publish_packet_get,
                             test_nx_azure_iot_log_success };
INT number_of_tests =  sizeof(tests)/sizeof(tests[0]);

    printf("Number of tests %d\r\n", number_of_tests);
    for (INT index = 0; index < number_of_tests; index++)
    {
        tests[index]();
    }
}
